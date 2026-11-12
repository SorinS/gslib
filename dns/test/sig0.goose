// SIG(0) against miekg/dns (the sig0 rows of vectors/tsig.txt, from
// scripts/oracle): miekg's messages signed with RSASHA256 and
// ECDSAP256SHA256 KEYs verified, refused when expired or changed, and
// the same messages signed here with miekg's keys verified.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.dnssec;
import gslib.dns.sig0;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

fn check_sig0(r: tv::Row&) {
    var k: u8[>..] = [];
    unhex(k, r.next());
    var w: u8[>..] = [];
    unhex(w, r.next());
    let priv_text = r.next();
    let kr = dns::rr_at(k, 0);
    tv::check_int("SIG(0) verify", dns::sig0_verify(w, kr.name(k), kr.rdata(k), 1800000000), dns::OK);
    tv::check_int("SIG(0) expired", dns::sig0_verify(w, kr.name(k), kr.rdata(k), 2000000001), dns::ERR_TIME);
    var bad: u8[>..] = [];
    bad.append(w);
    bad[13] ^= 1;
    tv::check("SIG(0) changed byte", dns::sig0_verify(bad, kr.name(k), kr.rdata(k), 1800000000) != dns::OK);
    // Signed here: the message without miekg's SIG, signed again.
    let pk, pe = dns::read_private_key(priv_text, kr.rdata(k));
    tv::check_int("SIG(0) key", pe, dns::OK);
    var m = dns::Msg { .. };
    dns::unpack(w, m);
    var ex: u8[>..] = [];
    dns::each_rr(m.extra) { rr => if rr.rtype != dns::TYPE_SIG { dns::rr_copy(ex, m.extra, rr); } };
    m.extra.clear();
    m.extra.append(ex);
    var mine: u8[>..] = [];
    dns::pack(m, mine);
    tv::check_int("SIG(0) sign", dns::sig0_sign(mine, pk, kr.name(k), kr.rdata(k), 1700000000, 2000000000), dns::OK);
    tv::check_int("SIG(0) verify own", dns::sig0_verify(mine, kr.name(k), kr.rdata(k), 1800000000), dns::OK);
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

fn main() {
    tv::each_row(str(vectors_dir(), "/tsig.txt")) { r => if r.next() == "sig0" { check_sig0(r); } };
    tv::done("sig0");
}
