// tsig: transaction signatures (RFC 8945), a secret shared by client and
// server, as for zone transfers and dynamic updates. The client signs a
// packed query; the server finds which key signed it, verifies it, and
// signs its reply over the query's MAC; the client verifies the reply.
// A wrong secret and a clock outside the fudge are refused, and the
// messages of a multi-part answer (a zone transfer) are chained with
// timers-only signatures.
//
//   goose examples/dns/tsig.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.tsig;

fn check(what: const u8[:], e: i64) {
    guard e == dns::OK else { print("tsig: ", what, ": ", dns::error_text(e)); exit(1); }
}

fn main() {
    // The key both sides have: a name and a secret, given in base64 as
    // BIND's `tsig-keygen` writes it.
    let key_name = "transfer.example.com.";
    let secret, ok = dns::tsig_secret("c2VjcmV0IGtleSBmb3IgdGhlIGV4YW1wbGUgb25seQ==");
    guard ok else { print("tsig: bad base64"); exit(1); }
    let now = time_ns() / 1000000000;

    // Client: the query packed, then signed; the MAC kept for the reply.
    var q = dns::Msg { .. };
    dns::set_question(q, "example.com.", dns::TYPE_SOA);
    var w: u8[>..] = [];
    dns::pack(q, w);
    let unsigned_len = w.len;
    let qmac, se = dns::tsig_sign(w, key_name, dns::HMAC_SHA256, secret, 300, now, "", false);
    check("sign the query", se);
    print("query: ", unsigned_len, " bytes, ", w.len, " signed");

    // Server: which key? Then the MAC and the time.
    let kn, alg, ke = dns::tsig_key(w);
    check("tsig_key", ke);
    print("server: signed with ", dns::name_text(kn), " (", dns::name_text(alg), ")");
    let rmac, ve = dns::tsig_verify(w, secret, "", false, now);
    check("verify the query", ve);
    // The query as it was sent, the TSIG record taken off.
    var plain: u8[>..] = [];
    check("tsig_strip", dns::tsig_strip(w, plain));
    var req = dns::Msg { .. };
    check("unpack", dns::unpack(plain, req));
    var resp = dns::Msg { .. };
    dns::set_reply(resp, req);
    dns::new_rr(resp.answer, "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026010101 7200 3600 1209600 300");
    var rw: u8[>..] = [];
    dns::pack(resp, rw);
    // The reply's signature covers the request's MAC.
    let replymac, re = dns::tsig_sign(rw, key_name, dns::HMAC_SHA256, secret, 300, now, rmac, false);
    check("sign the reply", re);

    // Client: the reply checked against the query's MAC.
    let m2, ce = dns::tsig_verify(rw, secret, qmac, false, now);
    check("verify the reply", ce);
    var r = dns::Msg { .. };
    dns::unpack(rw, r);
    print("client: reply verified, ", dns::rr_string(r.answer, dns::rr_at(r.answer, 0)));

    // What is refused: another secret, a clock 10 minutes off, a reply
    // checked against another request's MAC.
    let other, ok2 = dns::tsig_secret("YW5vdGhlciBzZWNyZXQ=");
    let x1, e1 = dns::tsig_verify(w, other, "", false, now);
    let x2, e2 = dns::tsig_verify(w, secret, "", false, now + 600);
    let x3, e3 = dns::tsig_verify(rw, secret, "not the query's MAC", false, now);
    print("wrong secret: ", dns::error_text(e1), "; clock off: ", dns::error_text(e2), "; wrong request: ", dns::error_text(e3));
    guard e1 == dns::ERR_SIG && e2 == dns::ERR_TIME && e3 == dns::ERR_SIG else { print("tsig: a bad signature accepted"); exit(1); }

    // A zone transfer's second message: signed timers-only over the first
    // reply's MAC, and checked the same way.
    var more = dns::Msg { .. };
    dns::set_reply(more, req);
    more.question.clear();
    dns::new_rr(more.answer, "www.example.com. 300 IN A 192.0.2.80");
    var mw: u8[>..] = [];
    dns::pack(more, mw);
    let mm, me = dns::tsig_sign(mw, key_name, dns::HMAC_SHA256, secret, 300, now, replymac, true);
    check("sign the next message", me);
    let mm2, mve = dns::tsig_verify(mw, secret, m2, true, now);
    check("verify the next message", mve);
    print("second message of a transfer: verified over the first one's MAC");
}
