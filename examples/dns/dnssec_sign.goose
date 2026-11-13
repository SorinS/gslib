// dnssec_sign: signing a zone's records with DNSSEC, and checking them as
// a validator would. A zone-signing key (ECDSA P-256) and a key-signing
// key (Ed25519) generated, published as DNSKEY records with their key
// tags; an RRset signed with the ZSK and the DNSKEY RRset with the KSK;
// each RRSIG verified, its validity period checked, and refused when the
// data changes; the DS record for the parent; a key saved in BIND's
// private-key format and read back; NSEC3 hashes (RFC 5155's example)
// and the name an NSEC3 record covers.
//
//   goose examples/dns/dnssec_sign.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.dnssec;

fn check(what: const u8[:], e: i64) {
    guard e == dns::OK else { print("dnssec_sign: ", what, ": ", dns::error_text(e)); exit(1); }
}

// A new key for the zone and its DNSKEY record, appended to keys.
fn new_key(keys: u8[>..]&, zone: const u8[:], alg: u8, flags: u16) -> dns::PrivateKey {
    let k, e = dns::generate_key(alg, 0);
    check("generate_key", e);
    dns::rr_append(keys, zone, dns::TYPE_DNSKEY, dns::CLASS_INET, 3600, dns::dnskey_rdata(flags, alg, dns::public_key_bytes(k)));
    return k;
}

fn main() {
    let zone, ze = dns::name_parse("example.com.", []);
    let now = time_ns() / 1000000000;
    let inception = now - 3600;                 // an hour ago, for clocks behind
    let expiration = now + 30 * 86400;

    // The keys, as the zone publishes them.
    var keys: u8[>..] = [];
    let zsk = new_key(keys, zone, dns::ALG_ECDSAP256SHA256, dns::FLAG_ZONE);
    let ksk = new_key(keys, zone, dns::ALG_ED25519, dns::FLAG_ZONE | dns::FLAG_SEP);
    let zsk_rd = dns::rr_at(keys, dns::rr_index(keys, 0)).rdata(keys);
    let ksk_rd = dns::rr_at(keys, dns::rr_index(keys, 1)).rdata(keys);
    dns::each_rr(keys) { rr => print(dns::rr_string(keys, rr), "  ; key tag ", dns::key_tag(rr.rdata(keys))); };

    // An RRset signed with the ZSK: an RRSIG record appended to sigs.
    var www: u8[>..] = [];
    dns::new_rr(www, "www.example.com. 300 IN A 192.0.2.80");
    dns::new_rr(www, "www.example.com. 300 IN A 192.0.2.81");
    var sigs: u8[>..] = [];
    check("sign www", dns::sign_rrset(www, zsk, zone, zsk_rd, inception, expiration, sigs));
    // The DNSKEY RRset, signed with the KSK.
    check("sign DNSKEY", dns::sign_rrset(keys, ksk, zone, ksk_rd, inception, expiration, sigs));
    dns::each_rr(sigs) { rr => print(dns::rr_string(sigs, rr)); };

    // A validator's checks: the signature, then the time.
    let www_sig = dns::rr_at(sigs, dns::rr_index(sigs, 0)).rdata(sigs);
    let key_sig = dns::rr_at(sigs, dns::rr_index(sigs, 1)).rdata(sigs);
    check("verify www", dns::verify_rrsig(www_sig, www, zone, zsk_rd));
    check("verify DNSKEY", dns::verify_rrsig(key_sig, keys, zone, ksk_rd));
    guard dns::validity_period(www_sig, now) && !dns::validity_period(www_sig, expiration + 1) else {
        print("dnssec_sign: validity period");
        exit(1);
    }
    print("both RRSIGs verify and are within their validity period");
    var forged: u8[>..] = [];
    dns::new_rr(forged, "www.example.com. 300 IN A 192.0.2.80");
    dns::new_rr(forged, "www.example.com. 300 IN A 203.0.113.66");
    let fe = dns::verify_rrsig(www_sig, forged, zone, zsk_rd);
    let ke = dns::verify_rrsig(www_sig, www, zone, ksk_rd);
    print("a changed RRset: ", dns::error_text(fe), "; the wrong key: ", dns::error_text(ke));
    guard fe != dns::OK && ke != dns::OK else { print("dnssec_sign: a bad signature accepted"); exit(1); }

    // The DS record the parent zone publishes for the KSK.
    var ds: u8[>..] = [];
    check("DS", dns::ds_rdata(zone, ksk_rd, dns::DIGEST_SHA256, ds));
    var dsrr: u8[>..] = [];
    dns::rr_append(dsrr, zone, dns::TYPE_DS, dns::CLASS_INET, 86400, ds);
    print(dns::rr_string(dsrr, dns::rr_at(dsrr, 0)));

    // The ZSK saved as BIND's Kexample.com.+013+tag.private, and read back
    // (checked against its DNSKEY) to sign again.
    let saved = dns::private_key_string(zsk);
    print("private key file:\n", saved);
    let back, re = dns::read_private_key(saved, zsk_rd);
    check("read_private_key", re);
    var again: u8[>..] = [];
    check("sign again", dns::sign_rrset(www, back, zone, zsk_rd, inception, expiration, again));
    check("verify again", dns::verify_rrsig(dns::rr_at(again, 0).rdata(again), www, zone, zsk_rd));

    // NSEC3 (RFC 5155 Appendix A: SHA-1, 12 iterations, salt aabbccdd).
    let ex, exe = dns::name_parse("example.", []);
    let salt: u8[4] = [0xaa, 0xbb, 0xcc, 0xdd];
    let label = dns::nsec3_label(ex, 1, 12, salt);
    print("NSEC3 hash of example.: ", label);
    guard label == "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM" else { print("dnssec_sign: NSEC3 hash"); exit(1); }
    var n3: u8[>..] = [];
    check("NSEC3", dns::new_rr(n3, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX RRSIG DNSKEY NSEC3PARAM"));
    let nr = dns::rr_at(n3, 0);
    let missing, me = dns::name_parse("c.x.w.example.", []);
    guard dns::nsec3_match(nr.name(n3), nr.rdata(n3), ex) && dns::nsec3_cover(nr.name(n3), nr.rdata(n3), missing) else {
        print("dnssec_sign: NSEC3 match or cover");
        exit(1);
    }
    print("that NSEC3 record is example.'s, and proves c.x.w.example. does not exist");
}
