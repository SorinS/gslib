// edns: EDNS0 (RFC 6891), the OPT record and its options. A query with a
// buffer size, the DO bit, a client cookie, a client subnet and a request
// for the server's NSID; the server reading those from the unpacked query
// and answering with its NSID, a TCP keepalive and an Extended DNS Error;
// the client reading them back, one by one and by code. An rcode above 15
// (BADCOOKIE) lives partly in the OPT record, which pack handles.
//
//   goose examples/dns/edns.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

// Each option of a message's OPT record, by name.
fn show(who: const u8[:], m: const dns::Msg&) {
    let o = dns::opt_offset(m);
    guard o >= 0 else { print(who, ": no OPT record"); return; }
    let rr = dns::rr_at(m.extra, o);
    print(who, ": udp ", dns::opt_udp_size(rr), ", version ", dns::opt_version(rr), ", DO ", dns::opt_do(rr));
    let rd = rr.rdata(m.extra);
    dns::each_option(rd) { op =>
        print("  option ", op.code, ": ", op.data(rd).len, " bytes ", hex(op.data(rd)));
    };
}

fn main() {
    // The client's query.
    var q = dns::Msg { .. };
    dns::set_question(q, "www.example.com.", dns::TYPE_A);
    dns::set_edns0(q, 1232, true);
    dns::add_option(q, dns::EDNS0_COOKIE, "\x01\x02\x03\x04\x05\x06\x07\x08");
    var subnet: u8[>..] = [];
    dns::subnet_data(subnet, [192, 0, 2, 77], 24, 0);       // only 192.0.2.0/24 leaves
    dns::add_option(q, dns::EDNS0_SUBNET, subnet);
    dns::add_option(q, dns::EDNS0_NSID, "");
    var w: u8[>..] = [];
    dns::pack(q, w);
    show("query", q);

    // The server: what the client sent.
    var req = dns::Msg { .. };
    guard dns::unpack(w, req) == dns::OK else { print("edns: unpack"); exit(1); }
    let cs, ce, has_cookie = dns::find_option(req, dns::EDNS0_COOKIE);
    let ss, se, has_subnet = dns::find_option(req, dns::EDNS0_SUBNET);
    let ns, nse, wants_nsid = dns::find_option(req, dns::EDNS0_NSID);
    guard has_cookie && has_subnet && wants_nsid && ce - cs == 8 else { print("edns: the server lost an option"); exit(1); }
    print("server: client cookie ", hex(req.extra[cs..ce]), ", subnet option ", hex(req.extra[ss..se]),
          ", buffer ", dns::udp_size(req));

    // Its reply: an answer, and options of its own.
    var resp = dns::Msg { .. };
    dns::set_reply(resp, req);
    dns::new_rr(resp.answer, "www.example.com. 300 IN A 192.0.2.80");
    dns::set_edns0(resp, 1232, false);
    dns::add_option(resp, dns::EDNS0_NSID, "ns1.example.com");
    var ka: u8[>..] = [];
    dns::keepalive_data(ka, 300);                            // 30 seconds
    dns::add_option(resp, dns::EDNS0_TCP_KEEPALIVE, ka);
    var ede: u8[>..] = [];
    dns::ede_data(ede, 3, "served from the cache");          // 3: Stale Answer
    dns::add_option(resp, dns::EDNS0_EDE, ede);
    var rw: u8[>..] = [];
    dns::pack(resp, rw);

    // The client reads them.
    var r = dns::Msg { .. };
    guard dns::unpack(rw, r) == dns::OK else { print("edns: unpack reply"); exit(1); }
    show("reply", r);
    let a, b, has_nsid = dns::find_option(r, dns::EDNS0_NSID);
    guard has_nsid && r.extra[a..b] == "ns1.example.com" else { print("edns: no NSID"); exit(1); }
    print("the OPT record as dig shows it:");
    print(dns::rr_string(r.extra, dns::rr_at(r.extra, dns::opt_offset(r))));

    // BADCOOKIE is 23: its low 4 bits go in the header, the rest in OPT.
    var bad = dns::Msg { .. };
    dns::set_reply(bad, req);
    dns::set_edns0(bad, 1232, false);
    bad.hdr.rcode = dns::RCODE_BAD_COOKIE;
    var bw: u8[>..] = [];
    guard dns::pack(bad, bw) == dns::OK else { print("edns: pack BADCOOKIE"); exit(1); }
    var back = dns::Msg { .. };
    dns::unpack(bw, back);
    print("rcode ", dns::rcode_name(back.hdr.rcode), ": header bits ", bw[3] & 15, ", OPT bits ",
          dns::opt_extended_rcode(dns::rr_at(back.extra, dns::opt_offset(back))));
    guard back.hdr.rcode == dns::RCODE_BAD_COOKIE else { print("edns: the extended rcode was lost"); exit(1); }
}
