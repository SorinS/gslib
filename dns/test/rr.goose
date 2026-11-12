// Records against miekg/dns (vectors/rr.txt, from scripts/oracle over
// vectors/rr_corpus.txt): each one read from text into the same wire form
// as miekg's NewRR and PackRR, written back as miekg's String() writes
// it, and read again from that text into the same wire form. What miekg
// refuses, this refuses too.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

// Where this departs from miekg on purpose (README, "Departures").
fn departure(input: const u8[:]) -> bool {
    // miekg drops an AMTRELAY's gateway when the D-bit is set.
    if input == "amt.example. AMTRELAY 10 1 1 203.0.113.15" || input == "amt.example. AMTRELAY 10 1 3 amtrelays.example.com." { return true; }
    // miekg refuses an NSEC bitmap whose types are not in order; this sorts them.
    if input == "example.org. NSEC www.example.org. TYPE65534 A TYPE1234" { return true; }
    // miekg keeps what it can read of RFC 3597 rdata too long for its type; this refuses it.
    if input == "generic.example. MX \\# 6 000a01780000" { return true; }
    return false;
}

fn check_row(r: tv::Row&) {
        let input = r.next();
        let status = r.next();
        if departure(input) { return; }
        var got: u8[>..] = [];
        let res = dns::new_rr_result(got, input);
        if status == "err" {
            tv::check(str("refuses: ", input), res.err != dns::OK);
            return;
        }
        if res.err != dns::OK {
            tv::check(str("parses: ", input, " (", res.msg, ")"), false);
            return;
        }
        var want: u8[>..] = [];
        unhex(want, r.next());
        tv::check_eq(str("wire: ", input), got, want);
        let text = r.next();
        let rr = dns::rr_at(want, 0);
        let s = dns::rr_string(want, rr);
        tv::check_eq(str("text: ", input), s, text);
        // The text read back.
        var again: u8[>..] = [];
        let r2 = dns::new_rr_result(again, text);
        if r2.err != dns::OK && rr.rtype != dns::TYPE_OPT {
            tv::check(str("reads its own text: ", text, " (", r2.msg, ")"), false);
        } else if r2.err == dns::OK {
            tv::check_eq(str("round trip: ", input), again, want);
        }
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

fn main() {
    tv::each_row(str(vectors_dir(), "/rr.txt")) { r => check_row(r); };
    tv::done("rr");
}
