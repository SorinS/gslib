// sig0: SIG(0) (RFC 2931), a message signed with a public-key pair rather
// than TSIG's shared secret: the server needs only the client's KEY
// record. A host key (ECDSA P-256) is generated and published as a KEY
// record; an update is signed with it; the server verifies it against
// the KEY, and refuses it once a byte changes, after it expires, or
// with another host's key.
//
//   goose examples/dns/sig0.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.dnssec;
import gslib.dns.update;
import gslib.dns.sig0;

fn main() {
    // The client's key, and the KEY record the zone holds for it: the same
    // rdata as a DNSKEY (flags, protocol 3, algorithm, public key).
    let owner, oe = dns::name_parse("laptop.example.com.", []);
    let key, ke = dns::generate_key(dns::ALG_ECDSAP256SHA256, 0);
    guard ke == dns::OK else { print("sig0: generate_key: ", dns::error_text(ke)); exit(1); }
    let key_rd = dns::dnskey_rdata(0x0200, dns::ALG_ECDSAP256SHA256, dns::public_key_bytes(key));  // 0x0200: a host key
    var keyrr: u8[>..] = [];
    dns::rr_append(keyrr, owner, dns::TYPE_KEY, dns::CLASS_INET, 3600, key_rd);
    print(dns::rr_string(keyrr, dns::rr_at(keyrr, 0)));

    // The client's update: its own address. Signed for five minutes.
    var rr: u8[>..] = [];
    dns::new_rr(rr, "laptop.example.com. 300 IN A 192.0.2.44");
    var m = dns::Msg { .. };
    dns::set_update(m, "example.com.");
    dns::remove_rrset(m, rr);
    dns::insert(m, rr);
    var w: u8[>..] = [];
    dns::pack(m, w);
    let body = w.len;
    let now = time_ns() / 1000000000;
    let se = dns::sig0_sign(w, key, owner, key_rd, now - 60, now + 300);
    guard se == dns::OK else { print("sig0: sign: ", dns::error_text(se)); exit(1); }
    var signed = dns::Msg { .. };
    dns::unpack(w, signed);
    print("signed update, ", w.len, " bytes; its SIG record:");
    print(dns::rr_string(signed.extra, dns::rr_at(signed.extra, 0)));

    // The server: the signer named in the SIG is looked up (here, the KEY
    // above), and the message verified with it.
    let ve = dns::sig0_verify(w, owner, key_rd, now);
    guard ve == dns::OK else { print("sig0: verify: ", dns::error_text(ve)); exit(1); }
    print("verified with the KEY of ", dns::name_text(owner));

    // Refused: a changed byte, too late, another host's key.
    var bad: u8[>..] = [];
    bad.append(w);
    bad[body - 1] ^= 1;                // the address: 192.0.2.45
    let other, oke = dns::generate_key(dns::ALG_ECDSAP256SHA256, 0);
    let other_rd = dns::dnskey_rdata(0x0200, dns::ALG_ECDSAP256SHA256, dns::public_key_bytes(other));
    let e1 = dns::sig0_verify(bad, owner, key_rd, now);
    let e2 = dns::sig0_verify(w, owner, key_rd, now + 3600);
    let e3 = dns::sig0_verify(w, owner, other_rd, now);
    print("changed: ", dns::error_text(e1), "; an hour later: ", dns::error_text(e2), "; another key: ", dns::error_text(e3));
    guard e1 != dns::OK && e2 == dns::ERR_TIME && e3 != dns::OK else { print("sig0: a bad message accepted"); exit(1); }
}
