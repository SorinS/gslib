// DNSSEC against miekg/dns (vectors/dnssec.txt, from scripts/oracle) and
// RFC 8080 and RFC 6605's examples: miekg's keys read from its private-key
// files and matched to their DNSKEYs; its signatures (RSASHA1,
// RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSA P-256 and P-384,
// Ed25519) verified, and refused after a byte of the RRset changes; the
// same RRsets signed here with the same keys, into the same RRSIGs where
// the algorithm is deterministic (RSA, Ed25519) and verifying ones
// otherwise; DS records and key tags; NSEC3 hashes; validity periods.
import std;
import base64;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.dnssec;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

// The keys' DNSKEY records and private-key files, back to back, and where each is.
struct KeyAt { rec: i64, rec_end: i64, priv: i64, priv_end: i64 }

fn check_sig(keys: const u8[:], at: KeyAt, set: const u8[:], sig: const u8[:]) {
    let krr = dns::rr_at(keys, at.rec);
    let owner = krr.name(keys);
    let dnskey = krr.rdata(keys);
    let srr = dns::rr_at(sig, 0);
    let rrsig = srr.rdata(sig);
    let alg = dns::rrsig_alg(rrsig);
    tv::check_int(str("verify alg ", alg), dns::verify_rrsig(rrsig, set, owner, dnskey), dns::OK);
    // A changed byte of rdata: refused.
    var bad: u8[>..] = [];
    bad.append(set);
    bad[bad.len - 1] ^= 1;
    tv::check(str("refuses a changed RRset, alg ", alg), dns::verify_rrsig(rrsig, bad, owner, dnskey) != dns::OK);
    // A changed signature: refused.
    var badsig: u8[>..] = [];
    badsig.append(rrsig);
    badsig[badsig.len - 5] ^= 0x40;
    tv::check(str("refuses a changed signature, alg ", alg), dns::verify_rrsig(badsig, set, owner, dnskey) != dns::OK);
    // Signed here with miekg's key.
    let k, e = dns::read_private_key(keys[at.priv .. at.priv_end], dnskey);
    tv::check_int(str("private key, alg ", alg), e, dns::OK);
    var mine: u8[>..] = [];
    let se = dns::sign_rrset(set, k, owner, dnskey, dns::rrsig_inception(rrsig), dns::rrsig_expiration(rrsig), mine);
    tv::check_int(str("sign alg ", alg), se, dns::OK);
    if dns::is_ecdsa(alg) {
        let m = dns::rr_at(mine, 0);
        tv::check_int(str("verify own, alg ", alg), dns::verify_rrsig(m.rdata(mine), set, owner, dnskey), dns::OK);
    } else {
        // The record's own TTL is the set's here (RFC 4034 §3); the oracle chose another.
        let m = dns::rr_at(mine, 0);
        tv::check_eq(str("same RRSIG, alg ", alg), m.rdata(mine), rrsig);
        tv::check_eq(str("same RRSIG owner, alg ", alg), m.name(mine), srr.name(sig));
    }
}

fn rfc8080() {
    // RFC 8080 §6.1: Ed25519 is deterministic, so the RRSIG is remade exactly.
    var keyrr: u8[>..] = [];
    dns::new_rr(keyrr, "example.com. 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    var set: u8[>..] = [];
    dns::new_rr(set, "example.com. 3600 IN MX 10 mail.example.com.");
    var want: u8[>..] = [];
    dns::new_rr(want, "example.com. 3600 IN RRSIG MX 15 2 3600 1440021600 1438207200 3613 example.com. oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==");
    let kr = dns::rr_at(keyrr, 0);
    tv::check_int("RFC 8080 key tag", dns::key_tag(kr.rdata(keyrr)), 3613);
    let k, e = dns::read_private_key("Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=\n", kr.rdata(keyrr));
    tv::check_int("RFC 8080 private key", e, dns::OK);
    var got: u8[>..] = [];
    dns::sign_rrset(set, k, kr.name(keyrr), kr.rdata(keyrr), 1438207200, 1440021600, got);
    tv::check_eq("RFC 8080 RRSIG", got, want);
    let w = dns::rr_at(want, 0);
    tv::check_int("RFC 8080 verify", dns::verify_rrsig(w.rdata(want), set, kr.name(keyrr), kr.rdata(keyrr)), dns::OK);
    var ds: u8[>..] = [];
    dns::ds_rdata(kr.name(keyrr), kr.rdata(keyrr), 2, ds);
    var dsw: u8[>..] = [];
    dns::new_rr(dsw, "example.com. 3600 IN DS 3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b");
    tv::check_eq("RFC 8080 DS", ds, dns::rr_at(dsw, 0).rdata(dsw));
    tv::check("validity: inside", dns::validity_period(w.rdata(want), 1439000000));
    tv::check("validity: before", !dns::validity_period(w.rdata(want), 1438207199));
    tv::check("validity: after", !dns::validity_period(w.rdata(want), 1440021601));
}

fn rfc6605() {
    // RFC 6605 §6.1: ECDSA P-256's signature verifies (ECDSA is not deterministic there).
    var keyrr: u8[>..] = [];
    dns::new_rr(keyrr, "example.net. 3600 IN DNSKEY 257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
    var set: u8[>..] = [];
    dns::new_rr(set, "www.example.net. 3600 IN A 192.0.2.1");
    var sig: u8[>..] = [];
    dns::new_rr(sig, "www.example.net. 3600 IN RRSIG A 13 3 3600 20100909100439 20100812100439 55648 example.net. qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==");
    let kr = dns::rr_at(keyrr, 0);
    let s = dns::rr_at(sig, 0);
    tv::check_int("RFC 6605 key tag", dns::key_tag(kr.rdata(keyrr)), 55648);
    tv::check_int("RFC 6605 verify", dns::verify_rrsig(s.rdata(sig), set, kr.name(keyrr), kr.rdata(keyrr)), dns::OK);
    let k, e = dns::read_private_key("Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n", kr.rdata(keyrr));
    tv::check_int("RFC 6605 private key", e, dns::OK);
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

fn main() {
    var keys: u8[>..] = [];
    var at: KeyAt[>..] = [];
    var n = 0;
    tv::each_row(str(vectors_dir(), "/dnssec.txt")) { r =>
        let kind = r.next();
        if kind == "key" {
            let alg = r.next_int();
            let rec = keys.len;
            unhex(keys, r.next());
            let priv = keys.len;
            keys.append(r.next());
            at.push(KeyAt { rec, priv, priv, keys.len });
            let k, e = dns::read_private_key(keys[priv..], dns::rr_at(keys, rec).rdata(keys));
            tv::check_int(str("key ", alg), e, dns::OK);
            tv::check_eq(str("private key file ", alg), dns::private_key_string(k), keys[priv..]);
        } else if kind == "sig" {
            let i = r.next_int();
            var set: u8[>..] = [];
            unhex(set, r.next());
            var sig: u8[>..] = [];
            unhex(sig, r.next());
            check_sig(keys, at[i], set, sig);
        } else if kind == "ds" {
            var k: u8[>..] = [];
            unhex(k, r.next());
            let d = r.next_int();
            let tag = r.next_int();
            var want: u8[>..] = [];
            unhex(want, r.next());
            let kr = dns::rr_at(k, 0);
            tv::check_int("key tag", dns::key_tag(kr.rdata(k)), tag);
            var ds: u8[>..] = [];
            let e = dns::ds_rdata(kr.name(k), kr.rdata(k), d as! u8, ds);
            let w = dns::rr_at(want, 0);
            tv::check_eq(str("DS ", d), ds, w.rdata(want));
        } else if kind == "nsec3" {
            let name, e = dns::name_parse(r.next(), []);
            let iter = r.next_int();
            var salt: u8[>..] = [];
            unhex(salt, r.next());
            tv::check_eq("NSEC3 hash", dns::nsec3_label(name, 1, iter as! u16, salt), r.next());
        }
        n++;
    };
    rfc8080();
    rfc6605();
    tv::done("dnssec");
}
