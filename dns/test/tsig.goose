// TSIG against miekg/dns (vectors/tsig.txt, from scripts/oracle): for
// HMAC-SHA1, -SHA224, -SHA256, -SHA384 and -SHA512, a
// query, the reply signed over the query's MAC, and a next message signed
// timers-only over the reply's, each signed here into the same bytes as
// miekg's and miekg's verified; refused with a changed byte, the wrong
// secret, or a time outside the fudge. HMAC-MD5 signs and verifies its
// own (miekg no longer does it). Then a MAC size past the message, BADKEY
// for an unknown algorithm, a server's fudge cap, and a keyed zone transfer
// refusing an unsigned message. test/sig0.goose has the file's SIG(0)
// rows: TSIG needs no DNSSEC keys, so this runs where bignum's entropy
// does not (Windows).
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.tsig;
import gslib.dns.client;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

fn check_tsig(r: tv::Row&, timers: bool) {
    let alg = r.next();
    let key = r.next();
    let secret, ok = dns::tsig_secret(r.next());
    let t = r.next_int();
    var w: u8[>..] = [];
    unhex(w, r.next());
    var unsigned: u8[>..] = [];
    unsigned.append(w);
    var want: u8[>..] = [];
    unhex(want, r.next());
    var mac: u8[>..] = [];
    unhex(mac, r.next());
    var req: u8[>..] = [];
    unhex(req, r.next());
    let got_mac, e = dns::tsig_sign(w, key, alg, secret, 300, t, req, timers);
    tv::check_int(str("sign ", alg), e, dns::OK);
    tv::check_eq(str("signed ", alg, if timers { " timers" } else { "" }), w, want);
    tv::check_eq(str("mac ", alg), got_mac, mac);
    let vm, ve = dns::tsig_verify(want, secret, req, timers, t + 10);
    tv::check_int(str("verify ", alg), ve, dns::OK);
    tv::check_eq(str("verify mac ", alg), vm, mac);
    let vm2, te = dns::tsig_verify(want, secret, req, timers, t + 301);
    tv::check_int(str("outside the fudge ", alg), te, dns::ERR_TIME);
    var bad: u8[>..] = [];
    bad.append(want);
    bad[14] ^= 0x20;
    let vm3, be = dns::tsig_verify(bad, secret, req, timers, t);
    tv::check_int(str("changed byte ", alg), be, dns::ERR_SIG);
    var wrong: u8[>..] = [];
    wrong.append(secret);
    wrong[0] ^= 1;
    let vm4, we = dns::tsig_verify(want, wrong, req, timers, t);
    tv::check_int(str("wrong secret ", alg), we, dns::ERR_SIG);
    let kn, an, ke = dns::tsig_key(want);
    tv::check_eq(str("key name ", alg), dns::name_text(kn), key);
    var plain: u8[>..] = [];
    dns::tsig_strip(want, plain);
    tv::check_eq(str("stripped ", alg), plain, unsigned);
}

fn md5() {
    var m = dns::Msg { .. };
    dns::set_question(m, "example.", dns::TYPE_SOA);
    var w: u8[>..] = [];
    dns::pack(m, w);
    let mac, e = dns::tsig_sign(w, "k.", dns::HMAC_MD5, "secret", 300, 1700000000, [], false);
    tv::check_int("MD5 sign", e, dns::OK);
    tv::check_int("MD5 mac", mac.len, 16);
    let m2, e2 = dns::tsig_verify(w, "secret", [], false, 1700000000);
    tv::check_int("MD5 verify", e2, dns::OK);
    let m3, e3 = dns::tsig_sign(w, "k.", "hmac-sha3.", "secret", 300, 1700000000, [], false);
    tv::check_int("unknown algorithm", e3, dns::ERR_ALG);
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

// A TSIG whose MAC size runs past the message; BADKEY for an algorithm not
// done here; a request's fudge capped by the server's.
fn edges() {
    var m = dns::Msg { .. };
    dns::set_question(m, "example.", dns::TYPE_SOA);
    var w: u8[>..] = [];
    dns::pack(m, w);
    let mac, e = dns::tsig_sign(w, "k.", dns::HMAC_SHA256, "secret", 3000, 1700000000, [], false);
    var bad: u8[>..] = [];
    bad.append(w);
    let off, rd, fe = dns::find_tsig(bad);
    let an, p, ae = dns::read_name(bad, rd);
    dns::set16(bad, p + 8, 0xffff);
    var out: u8[>..] = [];
    tv::check_int("strip: MAC size past the end", dns::tsig_strip(bad, out), dns::ERR_RDATA);
    tv::check_int("strip: nothing kept", out.len, 0);
    let m1, e1 = dns::tsig_verify(w, "secret", [], false, 1700000600);
    tv::check_int("the request's fudge of 3000", e1, dns::OK);
    let m2, e2 = dns::tsig_verify_fudge(w, "secret", [], false, 1700000600, 300);
    tv::check_int("capped at the server's 300", e2, dns::ERR_TIME);
    var w2: u8[>..] = [];
    dns::pack(m, w2);
    let m3, e3 = dns::tsig_sign_error(w2, "k.", "hmac-sha3.", "secret", 300, 1700000000, [], false, dns::RCODE_BAD_KEY, []);
    tv::check_int("BADKEY for an unknown algorithm", e3, dns::OK);
    let kn, an2, ke = dns::tsig_key(w2);
    tv::check("BADKEY's TSIG names it", ke == dns::OK && dns::name_text(an2) == "hmac-sha3.");
}

// A zone transfer whose client has a key takes no unsigned message.
fn xfr_unsigned() {
    let secret_b64 = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng==";
    let secret, ok = dns::tsig_secret(secret_b64);
    var c = dns::Client { .. };
    c.tsig_name.append("xfr.example.");
    c.tsig_secret.append(secret_b64);
    var q = dns::Msg { .. };
    dns::set_question(q, "example.", dns::TYPE_AXFR);
    var w: u8[>..] = [];
    let req_mac, pe = dns::pack_query(c, q, w);
    let now = time_ns() / 1000000000;
    var r1 = dns::Msg { .. };
    dns::set_reply(r1, q);
    dns::new_rr(r1.answer, "example. 300 IN SOA ns.example. hm.example. 1 2 3 4 5");
    var w1: u8[>..] = [];
    dns::pack(r1, w1);
    let mac1, se = dns::tsig_sign(w1, "xfr.example.", dns::HMAC_SHA256, secret, 300, now, req_mac, false);
    var r2 = dns::Msg { .. };
    dns::set_reply(r2, q);
    r2.question.clear();
    dns::new_rr(r2.answer, "example. 300 IN SOA ns.example. hm.example. 1 2 3 4 5");
    var w2: u8[>..] = [];
    dns::pack(r2, w2);
    var mac: u8[>..] = [];
    mac.append(req_mac);
    var r = dns::Msg { .. };
    tv::check_int("AXFR: first message signed", dns::xfr_message(c, w, w1, r, mac, true), dns::OK);
    tv::check_int("AXFR: unsigned message refused", dns::xfr_message(c, w, w2, r, mac, false), dns::ERR_NO_SIG);
    let mac2, se2 = dns::tsig_sign(w2, "xfr.example.", dns::HMAC_SHA256, secret, 300, now, mac, true);
    tv::check_int("AXFR: the same signed", dns::xfr_message(c, w, w2, r, mac, false), dns::OK);
}

fn main() {
    tv::each_row(str(vectors_dir(), "/tsig.txt")) { r =>
        let kind = r.next();
        if kind == "tsig" { check_tsig(r, false); }
        else if kind == "timers" { check_tsig(r, true); }
    };
    md5();
    edges();
    xfr_unsigned();
    tv::done("tsig");
}
