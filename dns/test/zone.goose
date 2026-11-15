// Zone files against miekg/dns's ZoneParser (vectors/zone.txt, from
// scripts/oracle over vectors/zones/example.zone): $ORIGIN, $TTL,
// $INCLUDE with and without an origin, $GENERATE with modifiers, omitted
// owners, TTLs and classes, parentheses and comments; the same records,
// in the same order, and the error that ends the file in the same place.
// Then text with CRLF line ends, new_rr's defaults (no $INCLUDE), and
// records without rdata.
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

fn opts() -> dns::ZoneOptions {
    var o = dns::ZoneOptions { .. };
    let n, e = dns::name_parse("example.org.", []);
    o.origin = n;
    o.include = true;
    o.file.append("vectors/zones/example.zone");
    return o;
}

fn main() {
    var text: u8[>..] = [];
    if !read_file("vectors/zones/example.zone", text) { abort("no zone"); }
    var got: u8[>..] = [];
    let r = dns::parse_zone(text, opts(), got);
    var want: u8[>..] = [];
    var texts: u8[][>..] = [];
    var want_err = false;
    tv::each_row("vectors/zone.txt") { row =>
        let f = row.next();
        if f == "err" { want_err = true; } else { unhex(want, f); texts.push(str(row.next())); }
    };
    tv::check_eq("zone records", got, want);
    tv::check(str("zone ends in an error: ", r.msg), want_err == (r.err != dns::OK));
    tv::check_int("error line", r.line, 36);
    var k = 0;
    for t in texts {
        let off = dns::rr_index(got, k);
        if off >= 0 { tv::check_eq(str("record ", k), dns::rr_string(got, dns::rr_at(got, off)), t); }
        k++;
    }

    // The same zone with CRLF line ends reads the same (up to the error).
    var crlf: u8[>..] = [];
    for c in text { if c == '\n' { crlf.push('\r'); } crlf.push(c); }
    var got2: u8[>..] = [];
    let r2 = dns::parse_zone(crlf, opts(), got2);
    tv::check_eq("CRLF zone", got2, got);

    // $INCLUDE refused unless allowed.
    var o = opts();
    o.include = false;
    var got3: u8[>..] = [];
    let r3 = dns::parse_zone(text, o, got3);
    tv::check(str("$INCLUDE refused: ", r3.msg), r3.err != dns::OK && r3.line == 27);

    // new_rr: TTL 3600, class IN, the root as origin, the first record only.
    var one: u8[>..] = [];
    tv::check_int("new_rr", dns::new_rr(one, "a b.c. 1.2.3.4\nd. A 4.3.2.1"), dns::ERR_TYPE);
    one.clear();
    tv::check_int("new_rr two", dns::new_rr(one, "a. A 1.2.3.4\nd. A 4.3.2.1"), dns::OK);
    tv::check_int("new_rr one record", dns::rr_count(one), 1);
    tv::check_eq("new_rr text", dns::rr_string(one, dns::rr_at(one, 0)), "a.\t3600\tIN\tA\t1.2.3.4");
    one.clear();
    tv::check_int("new_rr empty", dns::new_rr(one, "; nothing\n"), dns::ERR_SYNTAX);
    // An empty quoted token where a TTL might be.
    one.clear();
    tv::check("new_rr empty token", dns::new_rr(one, "foo.example. \"\" IN A 192.0.2.1") != dns::OK);
    // new_rr reads no files.
    one.clear();
    let ri = dns::new_rr_result(one, "$INCLUDE vectors/zones/served.zone");
    tv::check(str("new_rr $INCLUDE refused: ", ri.msg), ri.err == dns::ERR_SYNTAX && one.len == 0);
    // No rdata: in new_rr, as dynamic update's deletes write it; not in a
    // zone, except where the type may have none.
    one.clear();
    tv::check_int("new_rr without rdata", dns::new_rr(one, "old.example. A"), dns::OK);
    var z: u8[>..] = [];
    let re = dns::parse_zone("@ 300 IN SOA\n", opts(), z);
    tv::check(str("zone: SOA without rdata: ", re.msg), re.err == dns::ERR_SYNTAX && z.len == 0);
    let re2 = dns::parse_zone("@ 300 IN SOA \\# 0\n", opts(), z);
    tv::check("zone: SOA as \\# 0", re2.err != dns::OK && z.len == 0);
    let re3 = dns::parse_zone("@ 0 NONE A\n@ 300 IN APL\n", opts(), z);
    tv::check_int("zone: a delete, an empty APL", re3.err, dns::OK);
    // LOC within RFC 1876's ranges: an altitude that is infinite, NaN or
    // past 32 bits of centimetres, latitude past the pole, seconds as NaN.
    let loc_bad: u8[][>..] = [
        "pe. LOC 2 N 5 E 7e750", "pe. LOC 2 N 5 E inf", "pe. LOC 2 N 5 E nan", "pe. LOC 2 N 5 E 42849673m",
        "pe. LOC 2 N 5 E -100000.01m", "pe. LOC 90 30 N 5 E 0m", "pe. LOC 2 N 180 0 1 W 0m", "pe. LOC 2 0 nan N 5 E 0m"];
    for t in loc_bad {
        var lr: u8[>..] = [];
        let le = dns::new_rr(lr, t);
        tv::check(str("LOC refused: ", t), le != dns::OK);
    }
    let loc_ok: u8[][>..] = ["pe. LOC 90 0 0 S 180 0 0 W -100000m", "pe. LOC 2 N 5 E 42849672.95m"];
    for t in loc_ok {
        var lr: u8[>..] = [];
        let le = dns::new_rr(lr, t);
        tv::check(str("LOC taken: ", t), le == dns::OK);
    }
    one.clear();
    let _ = dns::new_rr(one, "pe. LOC 2 N 5 E 42849672.95m");
    let lt = dns::rr_string(one, dns::rr_at(one, 0));
    tv::check(str("LOC highest altitude: ", lt), find(lt, " 42849672.95m ") >= 0);
    tv::done("zone");
}
